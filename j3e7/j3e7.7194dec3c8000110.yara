
rule j3e7_7194dec3c8000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7194dec3c8000110"
     cluster="j3e7.7194dec3c8000110"
     cluster_size="13"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos ebzlbe"
     md5_hashes="['11ffb319a70cfdba5dd15441d60b8402','34633f65d64ae376516109ddf982257d','d6f4581b9680fb680c77171a141318a8']"

   strings:
      $hex_string = { 7954687265616400066578697374730007666f724e616d650003676574000f6765744162736f6c7574655061746800126765744170706c69636174696f6e496e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
