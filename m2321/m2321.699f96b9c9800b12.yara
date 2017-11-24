
rule m2321_699f96b9c9800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.699f96b9c9800b12"
     cluster="m2321.699f96b9c9800b12"
     cluster_size="151"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys kryptik bcig"
     md5_hashes="['0144253febdd088d0592a910c44035c6','0279af07c15eef88d187e595b90480fd','24d8edafb5c2fd3a87612f7e6946f0be']"

   strings:
      $hex_string = { 3363d7a3dcafb92eefa705802577f80dd3e9ec7d04a6ce344ce3c2983a396902cb1049ebaa89815f6ae5cc0716da1847fe7cad4bed6b8df136a12f138f336815 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
