
rule m3e9_3b955ab9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3b955ab9c9800b16"
     cluster="m3e9.3b955ab9c9800b16"
     cluster_size="64"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['08bb4d4c1d17eb02480093f4b0b443cd','0c602ae65005b7455ccf102d14a98050','524f41d12702f2ac7c7a64350983cc86']"

   strings:
      $hex_string = { c19eabd18eeb8d0d173b9e2ef3d5c28069d20c0698c9e6c79ff0904061010f22914667182833fc7409c08f7b0e121f7cf15da11456b85453a85463181b8c4836 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
