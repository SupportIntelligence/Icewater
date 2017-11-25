
rule m3e9_0269850a50b152b3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0269850a50b152b3"
     cluster="m3e9.0269850a50b152b3"
     cluster_size="59"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cpsg riskware adload"
     md5_hashes="['03b1a84e5abe5dc1f8fde13c43407139','04654be3156dee63d66f6cb399c82bb8','58f6053f293cc2ae652a291af6921c00']"

   strings:
      $hex_string = { 7a595663861c7158d8043a854fd319e140c651892a64a3da030f162e15764973e2469dede8be536c959cb08e92ee07778279e0e328ef814b84bad40941311e42 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
