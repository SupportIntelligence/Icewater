
rule m231b_49999099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.49999099c2200b12"
     cluster="m231b.49999099c2200b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['281a881867303fe51d8cb7c406297845','5d3eee046fa1766b8096d145cfcae605','ccae4c338852c9ea43fa1d4b8e7f94fd']"

   strings:
      $hex_string = { 30323831364334343346464141394438314637323334394445364331393735393246364342373141354135383036424430453135343233453637363230383537 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
