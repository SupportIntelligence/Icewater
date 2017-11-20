
rule m3e9_13fb3852dea30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13fb3852dea30916"
     cluster="m3e9.13fb3852dea30916"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious unwanted"
     md5_hashes="['0d98497d88c2213c7a26764769a2e96e','1383ed7b129964c16e245512df31fc55','f7a36d4e27fb8ded71c33afe49415349']"

   strings:
      $hex_string = { 86ef5f8268fb523b2d3010215c0d54c349c2cd6a97e4b7dd24a24db81ec6260c962258e54e13d0f1a4aec95d92e361dbf436d899917dc12f8eb00b3e93322a09 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
