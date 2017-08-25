import "hash"

rule k3e9_139ca164cdcb9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ca164cdcb9932"
     cluster="k3e9.139ca164cdcb9932"
     cluster_size="16 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['43a709a9ca49d5b55697e4b30671385f', 'becbe2e1401c351d7e81abd4a0c8cbd8', '1c70748537112481d5998bb22d29be4b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24576,1024) == "de88ae07cff08473a9c10f1d9aaff856"
}

