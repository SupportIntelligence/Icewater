
rule k2321_09b2b532d85b4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09b2b532d85b4912"
     cluster="k2321.09b2b532d85b4912"
     cluster_size="108"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['04393823207ffa14bb00e908ed1cc77e','04a0f97c9361c5b05668bb16324d1722','2688fb9a9eb436df687a1ef2285038fe']"

   strings:
      $hex_string = { ee0d1895097d9edc60a6323de8d80c7d9015814076fef619c60a02b0a439369030a589cb1dba207c94210f0ea2aec2888ee17416558667a8a0ea48a3d41bd042 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
