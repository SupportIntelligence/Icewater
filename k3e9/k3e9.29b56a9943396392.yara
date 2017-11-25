
rule k3e9_29b56a9943396392
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.29b56a9943396392"
     cluster="k3e9.29b56a9943396392"
     cluster_size="19853"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis bundler"
     md5_hashes="['000207efcd7eb76051d0b28eb478c146','00093cf99b58f539f1a1da9cead017d4','003821b8d343ab06dd7f0ea50acc2d8e']"

   strings:
      $hex_string = { 3bb5a88e514b6fd42db7f88659d77f687ce2b442a3a40aaf74951c3c94088aaa649a0dd571c69e1aa1165669a26e2280149236f32ad34f0cf250fc8f7c76baf5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
