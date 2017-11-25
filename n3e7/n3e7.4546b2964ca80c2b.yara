
rule n3e7_4546b2964ca80c2b
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.4546b2964ca80c2b"
     cluster="n3e7.4546b2964ca80c2b"
     cluster_size="37"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['10891b0e670f06c412700f91b8741a8f','10891b0e670f06c412700f91b8741a8f','10891b0e670f06c412700f91b8741a8f']"

   strings:
      $hex_string = { 8ca672257865198f0c497b368a84cdcae8e5dccc8daf2dc3b6149067e2232cb712c8cbdba350a2ec531681ba00bef7015c039cc661ee95fb31e6d868c94663a0 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
