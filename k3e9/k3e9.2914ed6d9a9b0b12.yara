
rule k3e9_2914ed6d9a9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2914ed6d9a9b0b12"
     cluster="k3e9.2914ed6d9a9b0b12"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['2963f9602f66f94ed36e8ecde4f169a8','4801f9bd6c7a27b6c6e3801b52524f7c','c5a7f36143dc2a69c900604d5b1dfa25']"

   strings:
      $hex_string = { 9d1bc99a18c64a0f66a768b9911ab15eab54ca6502f2f6ba3f23a0adcff7990c0e9b25120ad40a4590461dac56e895d210b538522d8a510b633582588d304ec3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
