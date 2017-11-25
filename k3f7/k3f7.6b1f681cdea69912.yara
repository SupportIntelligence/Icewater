
rule k3f7_6b1f681cdea69912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.6b1f681cdea69912"
     cluster="k3f7.6b1f681cdea69912"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html iframe script"
     md5_hashes="['11876a86f008255c0b7dbbbe67d62a93','146251b105f6f8e92e17b3ba5160cade','f91af060ffed3ac1fbb07d46ba532920']"

   strings:
      $hex_string = { 323743444236452d414536442d313163662d393642382d3434343535333534303030302220636f6465626173653d22687474703a2f2f646f776e6c6f61642e6d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
