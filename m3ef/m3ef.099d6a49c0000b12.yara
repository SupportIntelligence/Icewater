import "hash"

rule m3ef_099d6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ef.099d6a49c0000b12"
     cluster="m3ef.099d6a49c0000b12"
     cluster_size="2804 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="linkury unwanted malicious"
     md5_hashes="['1ad3fbc561c6413559e529f18441f3ea', '1281f789bfccd2b8721139fe7aeeb7cd', '0ffdbfd758d156337fddc56e8954e6e6']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(38400,256) == "9dfffc89db9dc63f015ad770db7bfbcd"
}

