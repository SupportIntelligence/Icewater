
rule m3f7_639c9cc1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.639c9cc1c4000912"
     cluster="m3f7.639c9cc1c4000912"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0c1739a301b1696764bbde960c994455','41e674caa770677a41563d6d09caf90d','6bf6c1444deae609e693da5e2b7f98a5']"

   strings:
      $hex_string = { 726962652e7068703f6669643d323036353033323426616d703b733d73706f6b656e746f796f75223e0a3c696d67207372633d22687474703a2f2f7777772e66 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
