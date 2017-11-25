
rule m3e9_0b1488aadbbb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b1488aadbbb0932"
     cluster="m3e9.0b1488aadbbb0932"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="midie mikey nsis"
     md5_hashes="['1831a750742e02ba22cba4fb048c1a35','5e82aac43c9075b429d9a52ec53dda70','bd3a208a029d9002d59e64c88a5cfd53']"

   strings:
      $hex_string = { cd69eae61a68090e6ebdf427d507402d126517789190bb463cd1be82a3a91d6ba82aa1b3222b0637c2e05c3d988a62461bd7599a724f089c03c074e9f37f00fb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
