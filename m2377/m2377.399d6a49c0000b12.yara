
rule m2377_399d6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.399d6a49c0000b12"
     cluster="m2377.399d6a49c0000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['6de3f824abe0d7ad12d4431770906b45','6e1f89c8a31327c31de6e2ca64ad91a3','8cc905494034cf8555eefe65c98077e7']"

   strings:
      $hex_string = { a1f5a5392b7d9078e69418509f7f0caddad5d84f144243829d40b4712256a4b59cbc0dcdb4e0b351fef948f41f5cdf530f9849c2e78483741bf6e50137ca8145 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
