import "hash"

rule j3e9_1530dcc338a04d5e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.1530dcc338a04d5e"
     cluster="j3e9.1530dcc338a04d5e"
     cluster_size="566"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre bbxp bublik"
     md5_hashes="['00fcf61f8cb8a1059e1a7fe36c622570','022489b9486a7ee833041d34fd024f91','134deb1ad1f3add118fde03200599e50']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,4096) == "d1c99f7fac7e015965ad23494c6aa36c"
}

