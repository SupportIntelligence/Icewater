
rule m3e9_4ab05a42d9cfd112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4ab05a42d9cfd112"
     cluster="m3e9.4ab05a42d9cfd112"
     cluster_size="31"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik pronny"
     md5_hashes="['2c5bb66c2438557925685e0028e6fe74','5bd8785ed8a3027dd74c8b86a764b9d5','c201ccc558bee0a4e6710ba93a2b5b93']"

   strings:
      $hex_string = { 66676e5f6e59556f987a726f6d7990a2dcf9fffdfff7f7b7000000f8ffff0312282c20101111101a585765736c30667a635f5c75b3a79cc0cecdaea9aae6f2fa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
