## Setup
To set up the test environment first install docker-compose and clone this repo somewhere. Navigate to the root directory and run 
`docker-compose build adkg`

Once the docker image is built, it can be run with
`docker-compose run --rm adkg`

## Benchmarks
Once the docker image is running, a benchmark of the high-threshold batch DPSS can be performed by running
`pytest --benchmark-save=dpss_batch_ht --benchmark-min-rounds=3 benchmark/test_benchmark_dpss_ped_batch.py`
The t-threshold batch benchmark is run with
`pytest --benchmark-save=dpss_batch_lt --benchmark-min-rounds=3 benchmark/test_benchmark_dpss_lt.py`

Note that these benchmarks run all users on the same core and reshare many secrets, leading to a large runtime. 

## Tests
To get a better sense of how the protocols and subprotocols work, we point interested users to the tests directory. The high-threshold non-batched DPSS test case can be run via
`pytest tests\test_dpss_ped.py`
Test cases for the batched high-threshold and regular-threshold DPSS programs can be found in `tests\test_dpss_ped_batch.py` and `tests\test_dpss_ped_lt_batch.py` respectively. Many subprotocols used in our implementation have their own tests as well.