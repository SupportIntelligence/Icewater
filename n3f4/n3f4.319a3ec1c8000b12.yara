
rule n3f4_319a3ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.319a3ec1c8000b12"
     cluster="n3f4.319a3ec1c8000b12"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd malicious kryptik"
     md5_hashes="['1a9cf3691b7244b919272865b73e49d2','5bbf29b127d552cb28095c68c5e0a8ef','82bad40aa178bc3c48b9ade65670e577']"

   strings:
      $hex_string = { 57696e646f7773c2a0382e31202d2d3e0d0a2020202020203c212d2d3c737570706f727465644f532049643d227b31663637366337362d383065312d34323339 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
