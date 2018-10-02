
rule o26bb_0dbb6689de3b1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.0dbb6689de3b1932"
     cluster="o26bb.0dbb6689de3b1932"
     cluster_size="2866"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy softcnapp malicious"
     md5_hashes="['1520de06c949b8aab43c400b9f3797dda4e3f9cd','d93af87e84c9f6b21a91dc11d741601980c8122b','dd5a2c7c260308a54c99386d1649927899981ac9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.0dbb6689de3b1932"

   strings:
      $hex_string = { c40c85d2741985f6740f8bca2bcf8a078804394783ee0175f55f8bc25e5dc3e83565f8ffcc6a14b8225c5500e8569a020033db8d4dec53e8368702008b3d500b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
