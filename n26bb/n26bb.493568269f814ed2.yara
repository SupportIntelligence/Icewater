
rule n26bb_493568269f814ed2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.493568269f814ed2"
     cluster="n26bb.493568269f814ed2"
     cluster_size="242"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik fwvh malicious"
     md5_hashes="['329ce2ab3f294d8ea5d3ce717750011a4e1801dd','fe807c901863fd510b719fc21b04ab5ed179177b','78ce8af7b2ef3bf15939d01f6c248477732f94e3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.493568269f814ed2"

   strings:
      $hex_string = { 5066c0fcef04088b8da228394e8e9197f27190df0d4a832d056776a05660867ede1fbc36c851f31b9484ab3c3832102303433b208c7331d1b34ce7cd486849eb }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
