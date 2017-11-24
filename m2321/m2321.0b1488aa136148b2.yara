
rule m2321_0b1488aa136148b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b1488aa136148b2"
     cluster="m2321.0b1488aa136148b2"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="midie nsis xiazai"
     md5_hashes="['b0c746d92e1b44d324fd1544be4a5213','b411dd001a553c35e0c46e6d11ac0f1d','f77ec1b8b938f13697b049b211be1aa9']"

   strings:
      $hex_string = { 74c7bd026946000a8e03e44b611c17d876be446a818fa382fcf905cdb8e70f37333d67da8827c319685fef7a58a9a25edf512693cc322cb42040b2134a2f80b3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
