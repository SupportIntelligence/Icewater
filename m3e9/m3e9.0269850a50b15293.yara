
rule m3e9_0269850a50b15293
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0269850a50b15293"
     cluster="m3e9.0269850a50b15293"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cpsg riskware adload"
     md5_hashes="['19272548e5ad6c5c0230f1e6b1b9b30b','398da126df971ec3e545ef6b4cc4194b','e6fa0bbba7b66166d9a9d4e9c1ee7b91']"

   strings:
      $hex_string = { 7a595663861c7158d8043a854fd319e140c651892a64a3da030f162e15764973e2469dede8be536c959cb08e92ee07778279e0e328ef814b84bad40941311e42 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
