
rule k3e9_23ac369bcb4ce113
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.23ac369bcb4ce113"
     cluster="k3e9.23ac369bcb4ce113"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart backdoor berbew"
     md5_hashes="['7093cb953e6bc74e2eb488fa86ef4acf','7b1888fe79fd991ddde3b2dab2395dbd','d587833c8459313a41802e8c41143fde']"

   strings:
      $hex_string = { 636573734100000000930257616974466f7253696e676c654f626a65637400000097025769646543686172546f4d756c746942797465000000980257696e4578 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
