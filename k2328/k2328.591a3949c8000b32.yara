
rule k2328_591a3949c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2328.591a3949c8000b32"
     cluster="k2328.591a3949c8000b32"
     cluster_size="10"
     filetype = "application/xml"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script classic"
     md5_hashes="['0d944bfc592ab656fe4d27df1642795c','4be46295241a6246f19d94f6ad11ee18','f15506f9e309d551ab414c2917bfd9ea']"

   strings:
      $hex_string = { 786d6c2076657273696f6e3d22312e302220656e636f64696e673d227574662d38223f3e3c21444f43545950452068746d6c205055424c494320222d2f2f5733 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
