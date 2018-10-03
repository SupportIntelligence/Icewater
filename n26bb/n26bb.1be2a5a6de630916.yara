
rule n26bb_1be2a5a6de630916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1be2a5a6de630916"
     cluster="n26bb.1be2a5a6de630916"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="strictor injector heuristic"
     md5_hashes="['21263db68651f33bcfcd52a7f277cd424ba6f158','b649876b757a1cb2174678bc6213a65efdb576c1','cdac80d78ae8618f4d83e30fa4a9fae87fff30fd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1be2a5a6de630916"

   strings:
      $hex_string = { eb0fe93093feffbb03010380e88e96feff8bc35f5e5b5dc2100090558bec83c4f85356578b5d148b750833c05568cea2410064ff3064892085db7c0583fb027e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
