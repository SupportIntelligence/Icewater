
rule k3e9_31b162db9d9bd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.31b162db9d9bd932"
     cluster="k3e9.31b162db9d9bd932"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['2359ad0cade98971d99444bb3e32e63e','3bf96f89cef8402f65f6d7a42e82fa01','d45889ae3282e294a1368aeb56e8c72c']"

   strings:
      $hex_string = { ec394694e3c4d8597cf6f2db8b706fd193faad45ed63e918111d23e6afa10ac7b8a4e05a1a0698d76cc2691405fa211fb29b5c4e047da02e5ce74f660244f585 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
