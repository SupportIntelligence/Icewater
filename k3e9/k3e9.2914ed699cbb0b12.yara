
rule k3e9_2914ed699cbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2914ed699cbb0b12"
     cluster="k3e9.2914ed699cbb0b12"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['0602dad0a9fe5b0ae0e4f36f0b5df24b','5a6692cf4e27e224d66d3516c74e979b','e1bcd5d4b3b8a734b3c1be55da9603be']"

   strings:
      $hex_string = { 3b23929d1bce9a1cc24a0d642769b9e11ab15eab54ca6502f2f6ba2fc3afbdcff7990c0e9b25120ad40a4580461da856e895d220b5385c2d8a520ba33582688d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
