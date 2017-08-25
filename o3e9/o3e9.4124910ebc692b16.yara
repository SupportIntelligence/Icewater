import "hash"

rule o3e9_4124910ebc692b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4124910ebc692b16"
     cluster="o3e9.4124910ebc692b16"
     cluster_size="12342 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['044026ce3934aa2ed7cfe059a0027f25', '01f797fa45611d7c3796c2f3c69f8b76', '05e561daabb329db81b4c61127b8ce0e']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2937004,1058) == "5273f25dc0a964c6f5423daf1554c19c"
}

