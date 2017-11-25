
rule k3f7_6b1f681cdea6d112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.6b1f681cdea6d112"
     cluster="k3f7.6b1f681cdea6d112"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html iframe script"
     md5_hashes="['2e64124d95420747b319a42fc51f0236','de48148b86aba7e21ba663aa7f0ca4a9','fe21a318a67cd418f1d2989f261e6b6a']"

   strings:
      $hex_string = { 323743444236452d414536442d313163662d393642382d3434343535333534303030302220636f6465626173653d22687474703a2f2f646f776e6c6f61642e6d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
