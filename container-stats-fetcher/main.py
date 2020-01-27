import os
import json
import requests


def init_context(context):
    setattr(context.user_data, 'config', {
        'igz_session_id': os.environ['IGZ_SESSION_ID'],
        'igz_dashboard_url': os.environ['IGZ_DASHBOARD_URL'],
        'igz_stats_from_time': os.environ.get('IGZ_STATS_FROM_TIME', '-60s'),
    })


def handler(context, event):
    try:
        response_body = {'container_perf_stats': {}}
        igz_stats_from_time = context.user_data.config['igz_stats_from_time']

        containers_data = get_container_names(context)

        for container_id, container_name in containers_data.items():
            max_iops_read, \
                max_iops_write, \
                max_latency_per_io_read_msec, \
                max_latency_per_io_write_msec = get_container_max_io_and_latency(context,
                                                                                 container_id,
                                                                                 from_time=igz_stats_from_time)

            # build response chunk
            response_body['container_perf_stats'][container_id] = {
                'container_name': container_name,
                'max_iops_read': max_iops_read,
                'max_iops_write': max_iops_write,
                'max_latency_per_io_read_msec': max_latency_per_io_read_msec,
                'max_latency_per_io_write_msec': max_latency_per_io_write_msec,
            }

        return context.Response(body=response_body, status_code=201)

    except BaseException as exc:
        context.logger.warn_with('Event failed', exc=str(exc))
        return context.Response(body={'error': str(exc)}, status_code=500)


def get_container_names(context):
    igz_session_id = context.user_data.config['igz_session_id']
    igz_dashboard_url = context.user_data.config['igz_dashboard_url']

    response = requests.get(f'{igz_dashboard_url}/api/containers',
                            verify=False,  # if the system is provisioned with a prod cert - remove this
                            headers={
                                'Cookie': compile_auth_header(igz_session_id),
                            })

    if response.status_code != 200:
        raise RuntimeError(f'Failed to fetch containers. status={response.status_code}')

    containers_response_json = response.json()
    containers_data = containers_response_json['data']
    container_names = {container['id']: container['attributes']['name'] for container in containers_data}
    context.logger.info_with('Discovered existing containers', container_names=container_names)
    return container_names


def get_container_max_io_and_latency(context, container_id, from_time, interval='20s'):
    """
    Get max io and latency statistics for a container and return their max over the given time period (from_time)

    We're dealing with rates here:
        iops: io value of metric is diff from last timestamp, so for iops we need to devide by time diff
        latency: we want avg latency per io [in msec for friendliness]
    """
    igz_session_id = context.user_data.config['igz_session_id']
    igz_dashboard_url = context.user_data.config['igz_dashboard_url']

    context.logger.debug_with('Getting IO statistics for container', container_id=container_id, from_time=from_time)
    response = requests.get(f'{igz_dashboard_url}/api/containers/{container_id}/statistics',
                            verify=False,  # if the system is provisioned with a prod cert - remove this
                            headers={
                                'Cookie': compile_auth_header(igz_session_id),
                            },
                            params={
                                'filter': f'container.{container_id}.storage_pool.*.(io|latency).(read|write)',
                                'from': from_time,
                                'interval': interval,
                            })

    if response.status_code != 200:
        raise RuntimeError(f'Failed to fetch statistics for container {container_id}. status={response.status_code}')

    stats_response_json = response.json()
    context.logger.debug_with('Got container stats response', stats_response_json=stats_response_json)
    stats_data = stats_response_json['data']

    max_iops_read = 0
    max_iops_write = 0
    max_latency_per_io_read_msec = 0
    max_latency_per_io_write_msec = 0

    # stats id examples:
    # "container.1026.storage_pool.0.io.read"
    # "container.1026.storage_pool.1.io.write"
    # "container.1026.storage_pool.0.latency.write"

    # we'll need to cache those and use them for latency per io calc
    io_read_stats = None
    io_write_stats = None

    # extract io info
    for stat in stats_data:
        if 'io' in stat['id']:
            if stat['id'].endswith('read'):

                # cache those to be used for latency calc
                io_read_stats = stat['attributes']['datapoints']
                max_iops_read = get_max_rate(io_read_stats)

            elif stat['id'].endswith('write'):

                # cache those to be used for latency calc
                io_write_stats = stat['attributes']['datapoints']
                max_iops_write = get_max_rate(io_write_stats)

    # log if none
    if not max_iops_read and not max_iops_write:
        context.logger.warn_with('No io stats were extracted for container',
                                 container_id=container_id,
                                 max_iops_write=max_iops_write,
                                 max_iops_read=max_iops_read)

    # second round, to extract latency data - dependent on io
    for stat in stats_data:
        if 'latency' in stat['id']:
            if stat['id'].endswith('read') and io_read_stats is not None:
                max_latency_per_io_read_msec = max(get_latency_per_io(stat['attributes']['datapoints'],
                                                                      io_read_stats))

            elif stat['id'].endswith('write') and io_write_stats is not None:
                max_latency_per_io_write_msec = max(get_latency_per_io(stat['attributes']['datapoints'],
                                                                       io_write_stats))

    # log if none
    if not max_iops_read and not max_iops_write:
        context.logger.warn_with('No latency stats were extracted for container',
                                 container_id=container_id,
                                 max_latency_per_io_read_msec=max_latency_per_io_read_msec,
                                 max_latency_per_io_write_msec=max_latency_per_io_write_msec)

    return max_iops_read, max_iops_write, max_latency_per_io_read_msec, max_latency_per_io_write_msec


def compile_auth_header(session_id):
    cookie = {'sid': session_id}
    return 'session=j:' + json.dumps(cookie)


def get_max_rate(datapoints):
    """
    :param: datapoints - list of values of tuples: = [[x, y], ...] where x numerical value and y is epoch timestamp
    """

    # use zip to take diffs and output rage
    rates = [
        point[0] / (point[1] - prev_point[1])
        for point, prev_point in zip(datapoints[1:], datapoints[:-1])
    ]
    return max(rates)


def get_latency_per_io(lat_datapoints, io_datapoints):
    """
    zip() the list of latency.read/write values and io.read/write values and provide list of lat per io
    this is assuming the values are given at the same timestamps (second value in the tuple)
    IMPORTANT: latency in the api-received raw stats is in units of nano-seconds,
        we transform them to millisecond to match what the user is used to see in our dashboard
    """
    def safe_division(numerator, denominator):
        if not denominator:
            return 0
        return numerator / denominator

    latency_per_io_nsec = [
        safe_division(lat_point[0], io_point[0])
        for lat_point, io_point in zip(lat_datapoints, io_datapoints)
    ]

    # to msec because for consistency with our dashboard
    return [value / 10 ** 6 for value in latency_per_io_nsec]
