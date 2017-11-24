
rule k2319_5b3b62639ec30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5b3b62639ec30b12"
     cluster="k2319.5b3b62639ec30b12"
     cluster_size="8"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cryxos redirector redir"
     md5_hashes="['108f549b4734ff85419779c59ddf73ae','302e28940072e5fdd0de5b73f6b48f47','c9d65b8322ccd3536068343a1f446273']"

   strings:
      $hex_string = { 7652636d6f734a724f544c4d4465484d464b7a416143667c4945776669485a5579797853556743686a566e5a6e77484764507669786b4c754c67664c6873657c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
