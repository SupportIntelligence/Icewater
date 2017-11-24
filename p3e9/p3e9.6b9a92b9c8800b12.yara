
rule p3e9_6b9a92b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.6b9a92b9c8800b12"
     cluster="p3e9.6b9a92b9c8800b12"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector gate aovhryb"
     md5_hashes="['1d060ed8d646b562e4787036c8b42261','7f04276b05ef503fbe2ac90776de9c4c','fc08793644e3009a1c0ac76de26815ef']"

   strings:
      $hex_string = { 0c5aa0cbfa032175a777f8c5f46766f748865cc93de60893cdf64cde0e33a33238319b5390a9dceda1a52e026afb1bd6912f18d9ecccc1548207f3b68efdac10 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
