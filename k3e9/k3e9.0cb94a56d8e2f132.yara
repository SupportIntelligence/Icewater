import "hash"

rule k3e9_0cb94a56d8e2f132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0cb94a56d8e2f132"
     cluster="k3e9.0cb94a56d8e2f132"
     cluster_size="1193"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="unruy cycler clicker"
     md5_hashes="['011376d78a032efa9cd3d9d552693ca2','021f08108c739f699bbc2f57a44ef534','0c70866af8d99b6fff0f50f466a0bba9']"


   condition:
      
      filesize > 262144 and filesize < 1048576
      and hash.md5(0,65536) == "b618a8c6f0d40305ce00bf863277ff2a"
}

