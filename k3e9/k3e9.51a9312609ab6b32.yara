
rule k3e9_51a9312609ab6b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51a9312609ab6b32"
     cluster="k3e9.51a9312609ab6b32"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['aeefd6f220c816521197d7a53572a099','b45e5f6775a320e0e8017191889489e0','ba0bff4615a968586fa928a4e2b21907']"

   strings:
      $hex_string = { 33c0fcaa80fe0175bb80fa0172b62bfc83ff0672af8a04243c4074a83c2e74a454e848ffffffeb9cfec2eb02fec68ac1fcaaeb9453ff564081c40001000061c9 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
