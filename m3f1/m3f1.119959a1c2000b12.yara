
rule m3f1_119959a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f1.119959a1c2000b12"
     cluster="m3f1.119959a1c2000b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="triada androidos appad"
     md5_hashes="['05c1b84b7fd90c3e1e699af7c9901470','07879b350f45948caecfd79ba93e834c','e9e6c62b391d548ee890ea49b3550f0e']"

   strings:
      $hex_string = { cb23cf37440e093e82d01a21240d6ed9f31dfb267b4a74b14ec040f06225e6ee39966c2933a6930ca37a5ab0d195b66fb39328b5be4904cc5835839d5379eab4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
