
rule m2321_0b3d39a5ae210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b3d39a5ae210b12"
     cluster="m2321.0b3d39a5ae210b12"
     cluster_size="61"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod malob trojandropper"
     md5_hashes="['05df38be88a0979b3af0143d1dc91506','09894378027d7374aa33406b4cb2fe8a','40686aea60d6eddf563986d34bc63560']"

   strings:
      $hex_string = { 70c42cc8861d012bcccdd20995ae7b8441a62993c2a8e6474294ade9743e0d1feab4ed4e32f3492312dcb93f9830acd34cf480653491755427b787194d5b1b35 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
