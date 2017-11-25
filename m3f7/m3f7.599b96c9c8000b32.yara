
rule m3f7_599b96c9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.599b96c9c8000b32"
     cluster="m3f7.599b96c9c8000b32"
     cluster_size="45"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['024b34202bb3ef8ac13939ad4b3d3c6e','04b431133c4e859481352e2c212c4459','4344cce2fc30b4db8643edec6601fe88']"

   strings:
      $hex_string = { 373936303330313636355c783236636f6c6f72735c78336443677430636d467563334268636d56756442494c64484a68626e4e7759584a6c626e516142794e6d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
