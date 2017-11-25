
rule k3e9_29b56a99c3392392
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.29b56a99c3392392"
     cluster="k3e9.29b56a99c3392392"
     cluster_size="3469"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis bundler"
     md5_hashes="['0002e2cef0ecf61943bec7c06145506f','00384b08203fee92f5d3fb14d6ade5ae','00f9665eca77b65e11c9feb0fda5ec60']"

   strings:
      $hex_string = { 3bb5a88e514b6fd42db7f88659d77f687ce2b442a3a40aaf74951c3c94088aaa649a0dd571c69e1aa1165669a26e2280149236f32ad34f0cf250fc8f7c76baf5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
