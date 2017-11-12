
rule o3e9_165108c2969279b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.165108c2969279b2"
     cluster="o3e9.165108c2969279b2"
     cluster_size="1254"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr installmonster malicious"
     md5_hashes="['0000543253e0f3dc9cfa4255ce887ea3','000afff09f07f65369335066ba5a51e7','02e7620dda4826f832ae5ba02fbe4e54']"

   strings:
      $hex_string = { 08690ab6cb2f9fc57183d84d095c6019c0757d592e1c5d40dea1244077a201344f77e5dcdbb908fc804889bc8fc451b0b66c5189d5ddfb33665798f0a2c860cc }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
