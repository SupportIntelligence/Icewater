
rule m3e9_6b2f25a4d3a31b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f25a4d3a31b12"
     cluster="m3e9.6b2f25a4d3a31b12"
     cluster_size="135"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking qvod jadtre"
     md5_hashes="['0d64dcc389178832c084113f67bba11c','143cb366b9ea01327130a0112a55719f','5cd563521a4f47021016cf17fa97b63b']"

   strings:
      $hex_string = { 160d976285dd0d77d5b2979ff4f36d5d54a78ed58ce1aabf071672f14b159de1a13c8854afd720b3bd7f848feea3aafc507db5573219d5fd02bee478412cfb49 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
