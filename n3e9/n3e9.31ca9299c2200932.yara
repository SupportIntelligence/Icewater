import "hash"

rule n3e9_31ca9299c2200932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ca9299c2200932"
     cluster="n3e9.31ca9299c2200932"
     cluster_size="9 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="zusy orbus siggen"
     md5_hashes="['b3cd8cfc32029f609c5071209fcdaa57', 'aefe4fe6e511edd17484e6cf686dc71d', 'cb57f46250b983f53b664665028fdb4e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(446464,1024) == "7115d185c1213a6d0abcd06089003f2c"
}

