
rule n3ed_41b1e488c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.41b1e488c0000932"
     cluster="n3ed.41b1e488c0000932"
     cluster_size="47"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy quchispy malicious"
     md5_hashes="['055db5e3f6a1148c7fb922f81521d7c8','065c1374d123367ff51abf1536fc197c','48155e52286384e95ca319c0d52447a9']"

   strings:
      $hex_string = { 410d4d3ca3185ba05d3236b180425c6213dad0851878915a7654c1043810c52a0e81091c64e20713f0841b7ca10a17e4220121e80633e090036668e3019b50c3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
