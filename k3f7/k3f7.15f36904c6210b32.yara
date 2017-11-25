
rule k3f7_15f36904c6210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.15f36904c6210b32"
     cluster="k3f7.15f36904c6210b32"
     cluster_size="42"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html redirector"
     md5_hashes="['04917699bac2af1b6f8da6a7bb4311d6','04c3c950e2d58520b4b6091973842359','558544c1af3fc5151e519d9f22216058']"

   strings:
      $hex_string = { 3c215b43444154415b202a2f0a74696d656c792e646566696e6528202761693165635f63616c656e646172272c207b226578706f72745f75726c223a22776562 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
