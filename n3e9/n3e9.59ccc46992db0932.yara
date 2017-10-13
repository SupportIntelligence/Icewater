import "hash"

rule n3e9_59ccc46992db0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.59ccc46992db0932"
     cluster="n3e9.59ccc46992db0932"
     cluster_size="106 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['25756a16eb2345b65fc9328660fd97d2', '3ea3f7d39ce0c0576bdac72a416e46fd', '004e441afa6e0497a709f6273002ae32']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(616730,1047) == "dd68d691dfcd761e2a378343685d10a8"
}

