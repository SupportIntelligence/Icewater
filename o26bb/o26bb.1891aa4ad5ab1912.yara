
rule o26bb_1891aa4ad5ab1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.1891aa4ad5ab1912"
     cluster="o26bb.1891aa4ad5ab1912"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious accphish aedbb"
     md5_hashes="['4330dffd27665afc9226ecd479f49870efeab4fe','1257372d12c214aea5a69287347e5d7e19967bfb','5e8be61cc53c779e50b8bd431956edec36c47cfc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.1891aa4ad5ab1912"

   strings:
      $hex_string = { 00303132333435363738396162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a5f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
