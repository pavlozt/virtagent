# typical setup for monitoring tool
FROM  jonlabelle/network-tools:latest
# special ip route entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash","--login"]
