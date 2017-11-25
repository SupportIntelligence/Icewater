
rule m3f7_3b196a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.3b196a49c0000b12"
     cluster="m3f7.3b196a49c0000b12"
     cluster_size="14"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker html"
     md5_hashes="['191c3b89d4779db81d8a2ffd7884d2ef','36f0d9a16b92f2f3e2e68b475ee00b71','ff273b0008385626163347f44c8265d9']"

   strings:
      $hex_string = { 3b7d293b0a0909096a517565727928222e726174696e67626c6f636b22292e6d6f7573656f7665722866756e6374696f6e28297b436c69636b4a61636b466248 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
