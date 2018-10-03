
rule m26bb_4c57329bc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.4c57329bc6620b12"
     cluster="m26bb.4c57329bc6620b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi virut malicious"
     md5_hashes="['528ab82a678df6d8744ec33e5333add86486bf76','a948751bd3d04d6cfd5852c15d4192d0374b9d92','b0b7c8e78456b30fe1ab337896d9a22ffad8d7c3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.4c57329bc6620b12"

   strings:
      $hex_string = { 06e0a4e72f02f86977c800d0ee4fb9638c8239bd69b49456a2a0b818a87e84fadf0d4541b23514a3a1d4d8605644a53afcf1c5660a224292509f993413883cb1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
