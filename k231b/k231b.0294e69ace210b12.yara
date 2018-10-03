
rule k231b_0294e69ace210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k231b.0294e69ace210b12"
     cluster="k231b.0294e69ace210b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker likejack html"
     md5_hashes="['5f9c465b3aa0f2ff1260a58b6f5a1c4c55725dac','56a7ab98bcba96a91ab82ddd623f8ea61a86f372','5460afc7f1d8f8e78624fb83dc6f72eb4ce5844d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k231b.0294e69ace210b12"

   strings:
      $hex_string = { 67652827687474703a2f2f7777772e7261666973742e636f6d2f27293b223e47697269c59f2053617966616ec4b17a20596170c4b16e3c2f613e266e6273700a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
