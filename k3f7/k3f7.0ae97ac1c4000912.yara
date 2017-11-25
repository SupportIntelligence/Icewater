
rule k3f7_0ae97ac1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.0ae97ac1c4000912"
     cluster="k3f7.0ae97ac1c4000912"
     cluster_size="26"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['3018d445dccc9ec4800c24543c2573ea','387de1043c26afe8771c0ef16e83dad2','9e8dfbc8d524093f398ff2b14d3e0a90']"

   strings:
      $hex_string = { 3c215b43444154415b202a2f0a097661722064726f70646f776e203d20646f63756d656e742e676574456c656d656e7442794964282263617422293b0a096675 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
