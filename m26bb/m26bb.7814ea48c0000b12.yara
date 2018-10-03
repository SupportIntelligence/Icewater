
rule m26bb_7814ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.7814ea48c0000b12"
     cluster="m26bb.7814ea48c0000b12"
     cluster_size="54"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack akvggodi malicious"
     md5_hashes="['ab227b25b58b34822dfc97b420458fc261e0e810','14352665ae1be32424c1794e4d6a0391c16473be','49986b07845da72cc65d873a27f050feed74a349']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.7814ea48c0000b12"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
